
rule Trojan_Win32_Amadey_BAN_MTB{
	meta:
		description = "Trojan:Win32/Amadey.BAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_01_0 = {40 00 00 e0 2e 74 61 67 67 61 6e 74 00 30 } //2
		$a_03_1 = {40 00 00 c0 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 b0 06 00 00 ?? ?? 00 00 f6 02 } //3
		$a_01_2 = {a7 bb 2d 49 e3 da 43 1a e3 da 43 1a e3 da 43 1a b8 b2 40 1b ed da 43 1a b8 b2 46 1b 42 da 43 1a 36 b7 47 1b f1 da 43 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*3+(#a_01_2  & 1)*2) >=7
 
}