
rule Trojan_Win32_StopCrypt_PAB_MTB{
	meta:
		description = "Trojan:Win32/StopCrypt.PAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 75 fc a1 ?? ?? ?? ?? 01 45 fc b8 d6 38 00 00 01 45 fc 8b 45 08 8b 4d fc 8a 0c 01 8b 15 ?? ?? ?? ?? 88 0c 02 5e c9 } //2
		$a_03_1 = {55 8b ec 81 ec ?? ?? ?? ?? 56 33 f6 83 3d ?? ?? ?? ?? 37 0f 85 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=1
 
}