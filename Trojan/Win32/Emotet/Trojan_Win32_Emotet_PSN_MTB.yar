
rule Trojan_Win32_Emotet_PSN_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PSN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {0f b6 16 0f b6 c3 03 c2 8b f1 99 f7 fe 8b 45 ?? 8a 94 15 ?? ?? ?? ?? 30 10 } //1
		$a_81_1 = {48 73 47 75 52 32 76 52 34 46 41 39 74 75 4f 4c 74 61 45 75 4e 6a 53 78 59 59 42 5a 37 78 45 77 6f 43 45 35 57 56 77 66 77 61 44 } //1 HsGuR2vR4FA9tuOLtaEuNjSxYYBZ7xEwoCE5WVwfwaD
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}