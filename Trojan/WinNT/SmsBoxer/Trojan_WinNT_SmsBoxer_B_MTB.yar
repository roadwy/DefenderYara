
rule Trojan_WinNT_SmsBoxer_B_MTB{
	meta:
		description = "Trojan:WinNT/SmsBoxer.B!MTB,SIGNATURE_TYPE_JAVAHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {9b 00 17 1c 2a b4 00 0f a2 00 0f 1c 10 0d 9f 00 09 1c 10 0a } //1
		$a_01_1 = {1d 2b b6 00 1b a2 00 15 1c 2a 2b 1d b6 00 12 b6 00 11 60 3d 84 03 01 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}