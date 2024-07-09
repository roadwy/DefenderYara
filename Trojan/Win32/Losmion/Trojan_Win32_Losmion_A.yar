
rule Trojan_Win32_Losmion_A{
	meta:
		description = "Trojan:Win32/Losmion.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d 50 03 55 57 bd 80 80 80 80 8b 38 83 c0 04 8d 8f ff fe fe fe f7 d7 21 f9 21 e9 75 ?? 8b 38 83 c0 04 8d 8f ff fe fe fe } //1
		$a_01_1 = {52 65 67 20 41 64 64 20 22 48 4b 4c 4d 5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 72 75 6e 22 20 2f 76 65 20 2f 74 20 52 45 47 5f 53 5a 20 2f 64 } //1 Reg Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\run" /ve /t REG_SZ /d
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}