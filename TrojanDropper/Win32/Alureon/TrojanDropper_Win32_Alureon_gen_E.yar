
rule TrojanDropper_Win32_Alureon_gen_E{
	meta:
		description = "TrojanDropper:Win32/Alureon.gen!E,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {a5 22 02 0a dd dd 9d d9 a5 22 02 12 dd dd 9d d9 6a 22 02 f6 2d dd 53 fa dd 53 f6 dc 53 f2 dc 53 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}