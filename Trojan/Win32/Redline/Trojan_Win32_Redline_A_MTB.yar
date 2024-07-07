
rule Trojan_Win32_Redline_A_MTB{
	meta:
		description = "Trojan:Win32/Redline.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f 45 f0 89 75 ec 89 75 e4 8b 45 e8 83 c0 ff 89 45 e8 89 45 b0 8b 4d dc 83 d1 ff 89 4d dc 89 4d b4 8b 55 0c 42 89 55 0c e9 6b ff ff ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}