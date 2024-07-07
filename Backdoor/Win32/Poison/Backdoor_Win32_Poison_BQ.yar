
rule Backdoor_Win32_Poison_BQ{
	meta:
		description = "Backdoor:Win32/Poison.BQ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {e8 09 00 00 00 61 64 76 61 70 69 33 32 00 ff 90 01 04 ff 90 03 01 01 89 09 90 01 04 ff e8 06 00 00 00 6e 74 64 6c 6c 00 ff 90 01 04 ff 89 90 01 04 ff e8 07 00 00 00 75 73 65 72 33 32 00 ff 90 00 } //1
		$a_00_1 = {b8 00 06 40 00 ff d0 6a 00 e8 00 00 00 00 ff 25 00 04 40 00 } //1
		$a_00_2 = {5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 } //1 \shell\open\command
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}