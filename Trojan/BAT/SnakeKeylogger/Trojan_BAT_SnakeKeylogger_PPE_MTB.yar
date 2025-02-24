
rule Trojan_BAT_SnakeKeylogger_PPE_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.PPE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {5f 0d 09 08 7e ?? ?? ?? 04 5a 20 00 01 00 00 5d 59 20 00 01 00 00 58 20 ff 00 00 00 5f 0d 09 18 28 ?? ?? ?? 06 0d 09 66 20 ff 00 00 00 5f 0d 09 } //2
		$a_00_1 = {61 00 69 00 6e 00 76 00 65 00 73 00 74 00 69 00 6e 00 74 00 65 00 72 00 6e 00 61 00 74 00 69 00 6f 00 6e 00 61 00 6c 00 2e 00 63 00 6f 00 6d 00 2f 00 61 00 6a 00 61 00 78 00 2f 00 67 00 72 00 69 00 64 00 2f 00 47 00 6f 00 74 00 68 00 61 00 6d 00 73 00 2e 00 68 00 6d 00 } //2 ainvestinternational.com/ajax/grid/Gothams.hm
	condition:
		((#a_03_0  & 1)*2+(#a_00_1  & 1)*2) >=4
 
}