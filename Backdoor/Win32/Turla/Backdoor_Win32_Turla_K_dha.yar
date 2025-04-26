
rule Backdoor_Win32_Turla_K_dha{
	meta:
		description = "Backdoor:Win32/Turla.K!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f be 02 83 f0 55 8b 4d 08 03 4d fc 88 01 eb d9 } //1
		$a_01_1 = {2b 5b 25 64 2f 32 34 68 5d 20 25 30 32 64 2e 25 30 32 64 2e 25 30 34 64 } //1 +[%d/24h] %02d.%02d.%04d
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}