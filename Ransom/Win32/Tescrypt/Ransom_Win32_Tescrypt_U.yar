
rule Ransom_Win32_Tescrypt_U{
	meta:
		description = "Ransom:Win32/Tescrypt.U,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 03 00 00 "
		
	strings :
		$a_01_0 = {52 4f 47 55 45 5f 53 54 41 52 54 00 } //1 佒啇彅呓剁T
		$a_01_1 = {52 4f 47 55 45 5f 45 4e 44 00 } //1 佒啇彅久D
		$a_03_2 = {0f be 00 85 c0 74 ?? 8b 45 ?? 03 45 ?? 0f be 00 8b 4d ?? 0f af 4d ?? 03 c1 8b 4d ?? 03 4d ?? 0f b6 09 33 c8 8b 45 ?? 03 45 ?? 88 08 8b 45 ?? 40 89 45 ?? eb } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=100
 
}