
rule Trojan_Win32_Relinestealer_XG_MTB{
	meta:
		description = "Trojan:Win32/Relinestealer.XG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d 59 bf 88 9d ?? ?? ?? ?? 80 bd ?? ?? ?? ?? ?? 0f be d9 89 9d ?? ?? ?? ?? ?? ?? 83 c9 ?? 0f be c9 89 8d ?? ?? ?? ?? 8b 9d ?? ?? ?? ?? 33 9d ?? ?? ?? ?? 69 db ?? ?? ?? ?? 89 9d ?? ?? ?? ?? eb } //10
		$a_01_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}