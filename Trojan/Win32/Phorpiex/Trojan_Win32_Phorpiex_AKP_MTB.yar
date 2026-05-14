
rule Trojan_Win32_Phorpiex_AKP_MTB{
	meta:
		description = "Trojan:Win32/Phorpiex.AKP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d 85 f0 fb ff ff 50 68 60 52 41 00 ff 15 ?? ?? ?? ?? 8d 8d f0 fb ff ff 51 68 70 52 41 00 8d 95 f8 fd ff ff 52 ff 15 ?? ?? ?? ?? 83 c4 0c 8d 85 f8 fd ff ff 50 } //2
		$a_03_1 = {50 68 70 54 41 00 8d 8d f8 fd ff ff 51 ff 15 ?? ?? ?? ?? 83 c4 0c 8d 95 f8 fd ff ff 52 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}