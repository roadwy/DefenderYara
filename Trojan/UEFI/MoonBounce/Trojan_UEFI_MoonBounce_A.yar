
rule Trojan_UEFI_MoonBounce_A{
	meta:
		description = "Trojan:UEFI/MoonBounce.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 "
		
	strings :
		$a_01_0 = {c6 00 48 c7 40 01 89 5c 24 08 } //1
		$a_01_1 = {c6 00 48 c7 40 01 8b c4 48 89 } //1
		$a_03_2 = {7f 32 67 81 ?? ?? 41 55 48 cb 75 } //1
		$a_01_3 = {9c 51 50 4c 89 e8 48 ff c8 81 38 4d 5a 90 90 00 75 f5 e8 } //1
		$a_03_4 = {c3 cc cc e8 ?? ?? ?? ?? ?? ?? ?? [0-07] 83 f9 0e 49 8b f8 48 8b f2 8b d9 7c } //1
		$a_03_5 = {c3 cc cc e8 ?? ?? ?? ?? 56 48 83 ec 20 48 83 64 24 40 00 48 8b da 4c 8d 44 24 40 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1+(#a_03_5  & 1)*1) >=3
 
}