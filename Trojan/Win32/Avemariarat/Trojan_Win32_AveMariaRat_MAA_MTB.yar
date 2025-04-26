
rule Trojan_Win32_AveMariaRat_MAA_MTB{
	meta:
		description = "Trojan:Win32/AveMariaRat.MAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {99 f7 bd 6c ff ff ff 89 95 5c ff ff ff 81 7d ?? ?? ?? ?? ?? 74 ?? 8b 4d 80 03 4d ?? 0f be 11 8b 85 5c ff ff ff 0f be 4c 05 98 33 d1 8b 45 80 03 45 ?? 88 10 eb } //1
		$a_01_1 = {46 69 6e 64 46 69 72 73 74 46 69 6c 65 45 78 57 } //1 FindFirstFileExW
		$a_01_2 = {52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 ReadProcessMemory
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}