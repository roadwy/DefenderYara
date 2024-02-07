
rule Ransom_Win32_GandCrab_MTC_bit{
	meta:
		description = "Ransom:Win32/GandCrab.MTC!bit,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c1 80 b0 90 01 04 05 40 3d 2b 87 00 00 90 00 } //01 00 
		$a_01_1 = {4b 00 52 00 41 00 42 00 2d 00 44 00 45 00 43 00 52 00 59 00 50 00 54 00 2e 00 74 00 78 00 74 00 } //01 00  KRAB-DECRYPT.txt
		$a_01_2 = {43 00 52 00 41 00 42 00 2d 00 44 00 45 00 43 00 52 00 59 00 50 00 54 00 2e 00 74 00 78 00 74 00 } //01 00  CRAB-DECRYPT.txt
		$a_01_3 = {25 00 73 00 2e 00 4b 00 52 00 41 00 42 00 } //01 00  %s.KRAB
		$a_01_4 = {25 00 73 00 25 00 78 00 25 00 78 00 25 00 78 00 25 00 78 00 2e 00 6c 00 6f 00 63 00 6b 00 } //00 00  %s%x%x%x%x.lock
	condition:
		any of ($a_*)
 
}