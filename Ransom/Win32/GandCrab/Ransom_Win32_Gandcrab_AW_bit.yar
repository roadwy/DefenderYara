
rule Ransom_Win32_Gandcrab_AW_bit{
	meta:
		description = "Ransom:Win32/Gandcrab.AW!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec e8 00 00 00 00 3e 83 04 24 11 75 05 74 03 e9 28 14 58 ff e0 } //1
		$a_00_1 = {25 00 73 00 2e 00 4b 00 52 00 41 00 42 00 } //1 %s.KRAB
		$a_00_2 = {4b 00 52 00 41 00 42 00 2d 00 44 00 45 00 43 00 52 00 59 00 50 00 54 00 2e 00 74 00 78 00 74 00 } //1 KRAB-DECRYPT.txt
		$a_00_3 = {25 00 73 00 25 00 78 00 25 00 78 00 25 00 78 00 25 00 78 00 2e 00 6c 00 6f 00 63 00 6b 00 } //1 %s%x%x%x%x.lock
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}