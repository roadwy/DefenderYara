
rule Backdoor_Win32_Rescoms_KD{
	meta:
		description = "Backdoor:Win32/Rescoms.KD,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 00 03 c6 0f b7 0b 66 81 e1 ff 0f 0f b7 c9 03 c1 01 10 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}