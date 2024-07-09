
rule Trojan_Win32_GandCrypt_PVC_MTB{
	meta:
		description = "Trojan:Win32/GandCrypt.PVC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {0f b6 cb 03 f1 5b 3d 97 0d 00 00 73 90 09 13 00 8b 0d ?? ?? ?? ?? 88 98 ?? ?? ?? ?? 0f b6 b1 } //2
		$a_02_1 = {30 04 37 4e 79 90 09 05 00 e8 } //2
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*2) >=2
 
}