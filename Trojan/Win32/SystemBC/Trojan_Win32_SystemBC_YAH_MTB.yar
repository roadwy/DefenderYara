
rule Trojan_Win32_SystemBC_YAH_MTB{
	meta:
		description = "Trojan:Win32/SystemBC.YAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {ba 40 e5 6d 00 89 44 24 ?? 8b ce e8 ?? ?? ?? ?? ba 40 84 75 03 89 44 24 } //1
		$a_03_1 = {8b 44 24 18 8a 4c 14 1c 32 8e ?? ?? ?? ?? 88 0c 06 } //10
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*10) >=11
 
}