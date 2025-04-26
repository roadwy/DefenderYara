
rule TrojanSpy_Win32_Bancos_gen_S{
	meta:
		description = "TrojanSpy:Win32/Bancos.gen!S,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_03_0 = {8a 54 32 ff 80 ea ?? f6 d2 e8 90 09 0b 00 be ?? 00 00 00 8d 45 ?? 8b 55 } //1
		$a_01_1 = {23 6e 40 74 65 2a 72 2a 6e 2a 65 2a 74 23 62 23 61 2a 6e 2a 6b 69 23 6e 23 67 40 63 23 61 40 69 23 78 23 61 } //1 #n@te*r*n*e*t#b#a*n*ki#n#g@c#a@i#x#a
		$a_01_2 = {4d 6f 7a 23 69 6c 6c 61 20 46 69 72 65 23 66 6f 78 } //1 Moz#illa Fire#fox
		$a_01_3 = {63 6d 23 64 20 2f 6b 20 73 74 23 61 72 74 20 69 65 78 70 6c 23 6f 72 65 2e 65 78 23 65 20 68 74 74 70 73 3a 2f 2f 69 6e 74 65 72 6e 65 74 62 61 6e 6b 69 6e 67 2e 63 61 69 78 61 2e 67 6f 76 2e 62 72 } //1 cm#d /k st#art iexpl#ore.ex#e https://internetbanking.caixa.gov.br
		$a_01_4 = {5c 42 68 6f 4f 4b } //1 \BhoOK
		$a_01_5 = {40 69 65 23 78 70 6c 6f 23 72 65 23 2e 65 78 65 23 } //1 @ie#xplo#re#.exe#
		$a_01_6 = {49 25 6e 2a 74 23 65 25 72 25 6e 2a 65 40 74 23 20 23 45 25 78 2a 70 2a 6c 23 6f 25 72 2a 65 40 72 40 5f 23 53 25 65 2a 72 2a 76 23 65 25 72 2a } //1 I%n*t#e%r%n*e@t# #E%x*p*l#o%r*e@r@_#S%e*r*v#e%r*
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}