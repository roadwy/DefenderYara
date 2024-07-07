
rule Backdoor_Win32_Tofsee_J{
	meta:
		description = "Backdoor:Win32/Tofsee.J,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {50 00 32 00 50 00 48 00 45 00 4c 00 50 00 2e 00 49 00 43 00 4f 00 09 00 53 00 48 00 49 00 54 00 2e 00 53 00 48 00 49 00 54 00 28 00 00 00 10 00 00 00 20 00 00 00 01 00 04 00 00 00 00 00 c0 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 80 00 00 00 80 80 00 80 00 00 00 80 00 80 00 80 80 00 00 c0 c0 c0 00 80 80 80 00 00 00 ff 00 00 ff 00 00 00 ff ff 00 ff 00 00 00 ff 00 ff 00 ff ff 00 00 ff ff ff 00 11 11 10 00 00 01 11 11 11 10 0b bb bb b0 01 11 11 0b bb bb bb bb b0 11 10 bb bb b0 0b bb bb 01 10 bb bb 0f f0 bb bb 01 0b bb b0 ff ff 0b bb b0 0b bb 00 ff ff 00 bb b0 0b bb bb 0f f0 bb bb b0 0b bb bb 0f f0 bb bb b0 0b bb bb 0f f0 bb bb b0 0b bb bb 0f f0 bb bb b0 10 bb bb 0f f0 bb bb 01 10 bb bb 00 00 bb bb 01 11 0b bb bb } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}