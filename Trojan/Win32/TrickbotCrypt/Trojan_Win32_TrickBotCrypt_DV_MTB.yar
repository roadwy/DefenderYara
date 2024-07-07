
rule Trojan_Win32_TrickBotCrypt_DV_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.DV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 0c 02 80 f1 80 3b c6 73 90 01 01 8b ff 8a d0 2a d3 80 e2 80 32 10 32 d1 88 10 03 c7 3b c6 72 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}