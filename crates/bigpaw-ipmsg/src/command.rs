//! IPMsg 命令字:u32,低 8 位为命令号,高位为选项标志(设计文档 §6)。

pub const BR_ENTRY: u32 = 0x01;
pub const BR_EXIT: u32 = 0x02;
pub const ANSENTRY: u32 = 0x03;
pub const SENDMSG: u32 = 0x20;
pub const RECVMSG: u32 = 0x21;
pub const GETFILEDATA: u32 = 0x60;
pub const GETDIRFILES: u32 = 0x62;

pub const SENDCHECKOPT: u32 = 0x0000_0100;
pub const FILEATTACHOPT: u32 = 0x0020_0000;

pub struct Command(pub u32);

impl Command {
    pub fn num(&self) -> u32 {
        self.0 & 0xff
    }
    pub fn has_opt(&self, opt: u32) -> bool {
        self.0 & opt != 0
    }
}

pub fn build(num: u32, opts: &[u32]) -> u32 {
    opts.iter().fold(num, |acc, o| acc | o)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_num_extracts_low_byte() {
        let c = build(SENDMSG, &[SENDCHECKOPT]);
        assert_eq!(Command(c).num(), SENDMSG);
        assert!(Command(c).has_opt(SENDCHECKOPT));
        assert!(!Command(c).has_opt(FILEATTACHOPT));
    }

    #[test]
    fn file_attach_opt_combines() {
        let c = build(SENDMSG, &[FILEATTACHOPT]);
        assert_eq!(Command(c).num(), SENDMSG);
        assert!(Command(c).has_opt(FILEATTACHOPT));
    }
}
