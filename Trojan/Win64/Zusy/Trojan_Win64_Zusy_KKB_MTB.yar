
rule Trojan_Win64_Zusy_KKB_MTB{
	meta:
		description = "Trojan:Win64/Zusy.KKB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 04 00 00 "
		
	strings :
		$a_81_0 = {53 45 4c 45 43 54 20 44 69 73 70 6c 61 79 4e 61 6d 65 2c 20 44 69 72 65 63 74 69 6f 6e 2c 20 41 63 74 69 6f 6e 2c 20 45 6e 61 62 6c 65 64 2c 20 50 72 6f 66 69 6c 65 2c 20 41 70 70 6c 69 63 61 74 69 6f 6e 4e 61 6d 65 2c 20 4c 6f 63 61 6c 50 6f 72 74 2c 20 52 65 6d 6f 74 65 50 6f 72 74 20 46 52 4f 4d 20 4d 53 46 54 5f 4e 65 74 46 69 72 65 77 61 6c 6c 52 75 6c 65 } //10 SELECT DisplayName, Direction, Action, Enabled, Profile, ApplicationName, LocalPort, RemotePort FROM MSFT_NetFirewallRule
		$a_81_1 = {5c 4d 69 63 72 6f 73 6f 66 74 5c 45 64 67 65 5c 55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 5c 48 69 73 74 6f 72 79 } //5 \Microsoft\Edge\User Data\Default\History
		$a_81_2 = {5c 47 6f 6f 67 6c 65 5c 43 68 72 6f 6d 65 5c 55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 5c 48 69 73 74 6f 72 79 } //3 \Google\Chrome\User Data\Default\History
		$a_81_3 = {5c 4d 6f 7a 69 6c 6c 61 5c 46 69 72 65 66 6f 78 5c 50 72 6f 66 69 6c 65 73 5c 2a } //1 \Mozilla\Firefox\Profiles\*
	condition:
		((#a_81_0  & 1)*10+(#a_81_1  & 1)*5+(#a_81_2  & 1)*3+(#a_81_3  & 1)*1) >=19
 
}