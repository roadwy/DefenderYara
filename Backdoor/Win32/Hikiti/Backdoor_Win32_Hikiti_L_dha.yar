
rule Backdoor_Win32_Hikiti_L_dha{
	meta:
		description = "Backdoor:Win32/Hikiti.L!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 "
		
	strings :
		$a_00_0 = {25 00 63 00 55 00 70 00 6c 00 6f 00 61 00 64 00 20 00 66 00 61 00 69 00 6c 00 65 00 64 00 21 00 20 00 5b 00 52 00 65 00 6d 00 6f 00 74 00 65 00 20 00 65 00 72 00 72 00 6f 00 72 00 20 00 63 00 6f 00 64 00 65 00 3a 00 20 00 25 00 64 00 5d 00 } //1 %cUpload failed! [Remote error code: %d]
		$a_00_1 = {43 00 61 00 6e 00 27 00 74 00 20 00 6f 00 70 00 65 00 6e 00 20 00 73 00 68 00 65 00 6c 00 6c 00 21 00 } //1 Can't open shell!
		$a_00_2 = {44 00 47 00 47 00 59 00 44 00 53 00 59 00 52 00 4c 00 } //1 DGGYDSYRL
		$a_01_3 = {44 47 47 59 44 53 59 52 4c 00 } //1 䝄奇卄剙L
		$a_00_4 = {25 63 25 63 25 63 2e 65 78 65 20 2f 63 20 64 65 6c 20 22 25 73 22 00 } //1
		$a_00_5 = {2e 64 6c 6c 00 6c 61 75 6e 63 68 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=3
 
}