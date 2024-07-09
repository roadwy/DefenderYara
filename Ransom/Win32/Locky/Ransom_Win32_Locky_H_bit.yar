
rule Ransom_Win32_Locky_H_bit{
	meta:
		description = "Ransom:Win32/Locky.H!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {6c 6d 75 61 77 74 77 67 65 71 70 66 73 6d } //1 lmuawtwgeqpfsm
		$a_01_1 = {43 6d 4d 6f 76 65 4d 65 6d 6f 72 79 } //1 CmMoveMemory
		$a_03_2 = {83 ec 04 c6 04 24 0a 8d 35 ?? ?? ?? ?? 81 ee 21 e3 64 98 56 8d 35 ?? ?? ?? ?? 81 ee 21 e3 64 98 56 e8 ?? ?? ?? ?? 83 f8 00 0f 85 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}