
rule Backdoor_Win32_Caphaw_S{
	meta:
		description = "Backdoor:Win32/Caphaw.S,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {f6 e6 f3 48 76 f2 54 19 e8 0a 05 ca 61 76 81 5c 3a b5 f6 0c b0 3a 80 fc 4e 72 94 f6 89 f6 bb 7c } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}