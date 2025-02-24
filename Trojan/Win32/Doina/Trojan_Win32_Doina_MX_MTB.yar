
rule Trojan_Win32_Doina_MX_MTB{
	meta:
		description = "Trojan:Win32/Doina.MX!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {e8 3d 06 00 00 0f b7 f0 e8 89 73 00 00 56 50 57 68 00 00 40 00 e8 55 f0 ff ff 8b f0 e8 57 06 00 00 84 c0 } //1
		$a_01_1 = {6b 00 73 00 74 00 61 00 74 00 69 00 6f 00 2e 00 65 00 78 00 65 00 } //1 kstatio.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}