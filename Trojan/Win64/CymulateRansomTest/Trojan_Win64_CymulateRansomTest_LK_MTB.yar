
rule Trojan_Win64_CymulateRansomTest_LK_MTB{
	meta:
		description = "Trojan:Win64/CymulateRansomTest.LK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {55 73 65 72 73 5c 59 6f 61 76 53 68 61 68 61 72 61 62 61 6e 69 5c 73 6f 75 72 63 65 5c 72 65 70 6f 73 5c 77 69 6e 64 6f 77 73 2d 73 63 65 6e 61 72 69 6f 73 5c 50 61 79 6c 6f 61 64 73 5c 4e 61 74 69 76 65 52 61 6e 73 6f 6d 65 77 61 72 65 5c 78 36 34 5c 52 65 6d 6f 74 65 4b 65 79 5f } //01 00  Users\YoavShaharabani\source\repos\windows-scenarios\Payloads\NativeRansomeware\x64\RemoteKey_
		$a_01_1 = {41 50 54 5f 53 43 45 4e 41 52 49 4f } //01 00  APT_SCENARIO
		$a_01_2 = {61 74 74 61 63 6b 5f 69 64 } //01 00  attack_id
		$a_01_3 = {73 63 65 6e 61 72 69 6f 5f 69 64 } //01 00  scenario_id
		$a_01_4 = {2e 00 43 00 79 00 6d 00 43 00 72 00 79 00 70 00 74 00 } //01 00  .CymCrypt
		$a_01_5 = {67 00 65 00 74 00 2d 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 69 00 6f 00 6e 00 2d 00 6b 00 65 00 79 00 3f 00 74 00 6f 00 6b 00 65 00 6e 00 3d 00 } //00 00  get-encryption-key?token=
	condition:
		any of ($a_*)
 
}