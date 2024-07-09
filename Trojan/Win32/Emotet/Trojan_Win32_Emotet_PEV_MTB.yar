
rule Trojan_Win32_Emotet_PEV_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PEV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {03 c1 99 b9 ?? ?? ?? ?? f7 f9 89 95 ?? ?? ?? ?? 8b 55 ?? 03 95 ?? ?? ?? ?? 33 c0 8a 02 8b 8d ?? ?? ?? ?? 33 d2 8a 94 0d ?? ?? ?? ?? 33 c2 8b 4d ?? 03 8d ?? ?? ?? ?? 88 01 } //1
		$a_81_1 = {4f 58 59 4e 7c 69 61 7d 50 71 67 4f 3f 77 36 4e 69 76 7b 4e 6c 72 4a 58 70 55 6a 7c 39 4f 36 57 50 6f 78 70 37 35 6f 6d 67 56 4d 4a 35 24 6a 65 2a 40 35 4b 47 7b 50 45 6e 43 4d 2a 58 67 39 4e 72 35 35 79 69 59 48 61 79 } //1 OXYN|ia}PqgO?w6Niv{NlrJXpUj|9O6WPoxp75omgVMJ5$je*@5KG{PEnCM*Xg9Nr55yiYHay
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}