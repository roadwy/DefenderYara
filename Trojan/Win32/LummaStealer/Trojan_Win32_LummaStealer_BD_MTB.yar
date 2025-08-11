
rule Trojan_Win32_LummaStealer_BD_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.BD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b6 4d 0c 0f bf 55 f4 0f af d1 66 89 55 f4 0f b7 45 08 0f b6 4d ff 03 c8 88 4d ff } //3
		$a_03_1 = {03 d1 88 95 ?? ?? ?? ff 0f bf 85 ?? ?? ?? ff 03 05 } //2
	condition:
		((#a_01_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}