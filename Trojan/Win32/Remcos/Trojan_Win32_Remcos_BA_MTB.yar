
rule Trojan_Win32_Remcos_BA_MTB{
	meta:
		description = "Trojan:Win32/Remcos.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {83 c0 01 89 45 90 01 01 8b 4d 90 01 01 3b 8d 90 01 02 ff ff 7d 90 01 01 8b 45 90 01 01 99 f7 bd 90 01 02 ff ff 8b 85 90 01 02 ff ff 0f be 0c 10 8b 95 90 01 02 ff ff 03 55 90 01 01 0f be 02 33 c1 8b 8d 90 01 02 ff ff 03 4d 90 01 01 88 01 eb 90 00 } //1
		$a_03_1 = {c6 85 30 ff ff ff c6 85 90 01 02 ff ff c6 85 90 01 02 ff ff c6 85 90 01 02 ff ff c6 85 90 01 02 ff ff c6 85 90 01 02 ff ff c6 85 90 01 02 ff ff c6 85 90 01 02 ff ff c6 85 90 01 02 ff ff c6 85 90 01 02 ff ff c6 85 90 01 02 ff ff c6 85 90 01 02 ff ff 90 00 } //1
		$a_03_2 = {c6 85 74 fe ff ff c6 85 90 01 02 ff ff c6 85 90 01 02 ff ff c6 85 90 01 02 ff ff c6 85 90 01 02 ff ff c6 85 90 01 02 ff ff c6 85 90 01 02 ff ff c6 85 90 01 02 ff ff c6 85 90 01 02 ff ff 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}