
rule Trojan_Win32_Sefnit_AX{
	meta:
		description = "Trojan:Win32/Sefnit.AX,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {83 e8 1e 1b cb 39 8d ?? ?? ?? ?? 7c 0a 7f 59 39 85 ?? ?? ?? ?? 73 51 53 e8 } //1
		$a_03_1 = {75 1f 83 ef 1e 83 db 00 39 9d ?? ?? ?? ?? 7c 0a 7f 2c 39 bd ?? ?? ?? ?? 73 24 68 } //1
		$a_03_2 = {75 27 83 ef 78 83 db 00 39 9d ?? ?? ?? ?? 7c 12 0f 8f ?? ?? ?? ?? 39 bd ?? ?? ?? ?? 0f 83 ?? ?? ?? ?? 68 } //1
		$a_01_3 = {75 1d 83 ef 78 83 db 00 39 5e 04 7f 3b 7c 04 39 3e 73 35 68 } //1
		$a_00_4 = {6f 3a 20 72 65 73 75 6d 69 6e 67 20 66 72 6f 6d 20 69 64 6c 65 } //4 o: resuming from idle
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_00_4  & 1)*4) >=5
 
}