
rule Trojan_Win32_Galock_A{
	meta:
		description = "Trojan:Win32/Galock.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 03 6a 00 6a 00 6a 00 6a 00 6a ff 8b ?? ?? 90 17 08 01 01 01 01 01 01 01 01 50 51 52 53 54 55 56 57 ff 55 ?? 6a 32 ff 15 } //1
		$a_03_1 = {8d 4c 10 18 89 4d ?? 8b 55 ?? 8b 45 ?? 03 42 60 89 45 ?? 8b 4d 0c c1 e9 10 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}