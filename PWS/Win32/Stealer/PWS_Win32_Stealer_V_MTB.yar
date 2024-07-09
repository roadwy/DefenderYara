
rule PWS_Win32_Stealer_V_MTB{
	meta:
		description = "PWS:Win32/Stealer.V!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {a1 48 d6 41 00 8d 97 ?? ?? ?? ?? 8a 8c 3e ?? ?? ?? ?? 56 88 0c 06 8b 0d 48 d6 41 00 e8 ?? ?? ?? ?? 83 fe 64 75 ?? 68 38 95 41 00 ff 35 4c d6 41 00 ff 15 30 40 41 00 a3 40 d6 41 00 46 3b f3 72 } //1
		$a_02_1 = {0f be 04 0e 89 45 fc e8 ?? ?? ?? ?? 89 45 f8 8b 45 fc 33 45 f8 89 45 fc 8a 45 fc 88 04 0e 46 3b f2 7c } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}