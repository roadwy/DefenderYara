
rule Trojan_WinNT_SmsBoxer_A_MTB{
	meta:
		description = "Trojan:WinNT/SmsBoxer.A!MTB,SIGNATURE_TYPE_JAVAHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {03 3e 2a b4 00 0f 07 64 36 04 1c 15 04 6c 1c 15 04 70 9e 00 07 } //1
		$a_01_1 = {2a b4 00 0e 12 23 b9 00 1a 02 00 c0 00 0a 59 4c 2a b4 00 0c b9 00 1c 02 00 2a b4 00 0d b6 00 14 3d 2a b4 00 0f 9e 00 9c } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}