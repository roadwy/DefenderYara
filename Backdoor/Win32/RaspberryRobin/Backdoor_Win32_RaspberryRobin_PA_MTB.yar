
rule Backdoor_Win32_RaspberryRobin_PA_MTB{
	meta:
		description = "Backdoor:Win32/RaspberryRobin.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {ac 32 02 aa 42 49 [0-0a] 85 c9 90 13 80 3a 00 74 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}