
rule Trojan_Win32_Cobaltstrike_EH_MTB{
	meta:
		description = "Trojan:Win32/Cobaltstrike.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {01 02 8b 45 d8 03 45 b0 03 45 e8 89 45 b4 } //1
		$a_01_1 = {03 d8 8b 45 ec 31 18 83 45 e8 04 83 45 ec 04 8b 45 e8 3b 45 e4 72 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}