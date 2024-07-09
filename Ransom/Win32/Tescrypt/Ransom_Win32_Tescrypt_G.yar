
rule Ransom_Win32_Tescrypt_G{
	meta:
		description = "Ransom:Win32/Tescrypt.G,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {de ad be ef b9 10 00 00 00 be ?? ?? ?? ?? bf ?? ?? ?? ?? f3 a5 b8 ?? ?? ?? ?? 83 c4 18 a4 } //1
		$a_01_1 = {2e 6f 6e 69 6f 6e 2e 74 6f 2f 25 53 } //1 .onion.to/%S
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}