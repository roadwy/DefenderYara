
rule Trojan_Win32_Redline_DGX_MTB{
	meta:
		description = "Trojan:Win32/Redline.DGX!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b c7 c1 e8 05 03 45 ec 8d 0c 3b 33 c1 31 45 0c 2b 75 0c 81 c3 47 86 c8 61 ff 4d f8 c7 05 48 87 ba 02 19 36 6b ff 0f 85 54 ff ff ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}