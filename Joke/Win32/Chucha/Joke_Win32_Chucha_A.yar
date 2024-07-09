
rule Joke_Win32_Chucha_A{
	meta:
		description = "Joke:Win32/Chucha.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {43 48 55 43 48 41 00 00 55 8b ec 33 c0 55 68 ?? ?? 44 00 64 ff 30 64 89 20 ff 05 ?? ?? 44 00 75 2a b8 ?? ?? 44 00 b9 05 00 00 00 8b 15 ?? ?? 40 00 e8 ?? ?? ?? ?? b8 ?? ?? 44 00 b9 05 00 00 00 8b 15 ?? ?? 40 00 e8 ?? ?? ?? ?? 33 c0 5a 59 59 64 89 10 68 ?? ?? 44 00 c3 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}