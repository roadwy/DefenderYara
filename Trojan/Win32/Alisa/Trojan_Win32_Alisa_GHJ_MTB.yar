
rule Trojan_Win32_Alisa_GHJ_MTB{
	meta:
		description = "Trojan:Win32/Alisa.GHJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {b0 65 88 44 24 ?? 88 44 24 ?? 88 44 24 ?? 8d 44 24 ?? 50 51 c6 44 24 ?? 43 c6 44 24 ?? 72 c6 44 24 ?? 61 c6 44 24 ?? 74 c6 44 24 ?? 45 c6 44 24 ?? 76 c6 44 24 ?? 6e c6 44 24 ?? 74 c6 44 24 ?? 41 88 5c 24 } //10
		$a_80_1 = {43 68 37 44 65 6d 6f 36 2e 45 58 45 } //Ch7Demo6.EXE  1
	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*1) >=11
 
}