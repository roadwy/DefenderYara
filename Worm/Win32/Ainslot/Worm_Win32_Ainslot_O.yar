
rule Worm_Win32_Ainslot_O{
	meta:
		description = "Worm:Win32/Ainslot.O,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {5f 59 61 68 4f 6f 5f 5c 4d 79 20 4c 69 4e 6b 5c 42 6c 61 63 6b 53 68 61 64 65 73 5c 64 65 20 44 61 72 6b 20 45 79 65 5c 45 4d 49 4e 65 4d } //1 _YahOo_\My LiNk\BlackShades\de Dark Eye\EMINeM
		$a_01_1 = {40 7e 7e 40 49 6e 65 74 6e 74 20 43 6c 65 61 6e 65 61 61 72 40 7e 7e 40 } //1 @~~@Inetnt Cleaneaar@~~@
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}