
rule Trojan_Win64_Meterpreter_GAD_MTB{
	meta:
		description = "Trojan:Win64/Meterpreter.GAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_01_0 = {45 44 52 5f 61 74 74 61 63 6b 73 5f 70 61 74 68 3a 73 74 72 69 6e 67 } //2 EDR_attacks_path:string
		$a_01_1 = {5c 70 72 6f 67 72 61 6d 64 61 74 61 5c 43 79 6d 75 6c 61 74 65 5c 41 67 65 6e 74 5c 41 74 74 61 63 6b 73 4c 6f 67 73 } //2 \programdata\Cymulate\Agent\AttacksLogs
		$a_01_2 = {73 6f 75 72 63 65 5c 72 65 70 6f 73 5c 77 69 6e 64 6f 77 73 2d 73 63 65 6e 61 72 69 6f 73 5c 50 61 79 6c 6f 61 64 73 5c 43 79 6d 75 6c 61 74 65 53 74 61 67 65 6c 65 73 73 4d 65 74 65 72 70 72 65 74 65 72 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 43 79 6d 75 6c 61 74 65 53 74 61 67 65 6c 65 73 73 4d 65 74 65 72 70 72 65 74 65 72 2e 70 64 62 } //2 source\repos\windows-scenarios\Payloads\CymulateStagelessMeterpreter\x64\Release\CymulateStagelessMeterpreter.pdb
		$a_00_3 = {54 00 41 00 52 00 47 00 45 00 54 00 52 00 45 00 53 00 4f 00 55 00 52 00 43 00 45 00 } //1 TARGETRESOURCE
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_00_3  & 1)*1) >=7
 
}