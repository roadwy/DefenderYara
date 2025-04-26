
rule Trojan_Win32_Alureon_gen_X{
	meta:
		description = "Trojan:Win32/Alureon.gen!X,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c6 45 0b 01 e9 ?? ?? ?? ?? b8 43 46 00 00 66 39 85 ?? ?? ?? ?? 0f 85 ?? ?? ?? ?? 66 83 bd ?? ?? ?? ?? 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}