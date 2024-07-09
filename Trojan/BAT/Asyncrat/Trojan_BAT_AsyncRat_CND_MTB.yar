
rule Trojan_BAT_AsyncRat_CND_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.CND!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 09 00 00 "
		
	strings :
		$a_03_0 = {07 08 9a 0d 7e ?? ?? ?? ?? 09 6f ?? ?? ?? ?? 6f ?? ?? ?? ?? 2d 12 7e ?? ?? ?? ?? 09 6f ?? ?? ?? ?? 6f ?? ?? ?? ?? 2c 25 17 0a 02 2c } //5
		$a_81_1 = {6f 6c 6c 79 64 62 67 } //1 ollydbg
		$a_81_2 = {69 64 61 77 36 34 } //1 idaw64
		$a_81_3 = {78 36 34 64 62 67 } //1 x64dbg
		$a_81_4 = {77 69 6e 64 62 67 } //1 windbg
		$a_81_5 = {64 6e 53 70 79 } //1 dnSpy
		$a_81_6 = {53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 57 69 6e 33 32 5f 50 72 6f 63 65 73 73 6f 72 } //1 SELECT * FROM Win32_Processor
		$a_81_7 = {53 65 6c 65 63 74 20 2a 20 46 72 6f 6d 20 57 69 6e 33 32 5f 43 6f 6d 70 75 74 65 72 53 79 73 74 65 6d } //1 Select * From Win32_ComputerSystem
		$a_81_8 = {53 65 6c 65 63 74 20 2a 20 66 72 6f 6d 20 57 69 6e 33 32 5f 50 72 6f 63 65 73 73 6f 72 } //1 Select * from Win32_Processor
	condition:
		((#a_03_0  & 1)*5+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1) >=13
 
}