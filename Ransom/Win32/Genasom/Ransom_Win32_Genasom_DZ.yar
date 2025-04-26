
rule Ransom_Win32_Genasom_DZ{
	meta:
		description = "Ransom:Win32/Genasom.DZ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {01 00 03 40 3c 8b 40 08 0b c0 75 01 c3 6a 00 e8 ?? ?? 01 00 8b d8 6a 10 6a 01 53 e8 ?? ?? 01 00 e9 a2 00 00 00 90 09 0d 00 e9 ?? ?? 01 00 68 ?? ?? 42 00 e8 } //1
		$a_01_1 = {48 00 79 00 64 00 65 00 2e 00 65 00 78 00 65 00 } //1 Hyde.exe
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}