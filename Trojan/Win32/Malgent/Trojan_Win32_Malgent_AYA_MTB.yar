
rule Trojan_Win32_Malgent_AYA_MTB{
	meta:
		description = "Trojan:Win32/Malgent.AYA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {81 bd 24 fd ff ff ed ed a4 35 76 02 33 c9 b8 07 00 00 00 83 e8 01 83 f8 0a 74 05 83 c0 02 eb 08 8d 85 24 fd ff ff 33 c0 33 c0 ff 85 24 fd ff ff 85 c9 75 cc e8 87 f2 ff ff e8 02 f1 ff ff 33 c9 33 c0 3b c1 } //2
		$a_01_1 = {53 00 69 00 74 00 4e 00 6f 00 77 00 } //1 SitNow
		$a_01_2 = {73 00 69 00 74 00 63 00 6f 00 6d 00 2e 00 65 00 78 00 65 00 } //1 sitcom.exe
		$a_01_3 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 IsDebuggerPresent
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}