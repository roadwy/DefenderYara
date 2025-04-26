
rule Trojan_Win32_Emotet_PDJ_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PDJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {0f b6 d3 03 c2 99 b9 ?? ?? ?? ?? f7 f9 8b 85 ?? ?? ?? ?? 40 83 c4 0c 89 85 ?? ?? ?? ?? 0f b6 94 15 ?? ?? ?? ?? 30 50 } //1
		$a_81_1 = {67 41 42 75 70 61 65 56 39 7a 61 77 61 68 6f 52 45 4f 35 32 32 32 56 66 33 31 41 36 4e 37 69 50 41 45 } //1 gABupaeV9zawahoREO5222Vf31A6N7iPAE
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}