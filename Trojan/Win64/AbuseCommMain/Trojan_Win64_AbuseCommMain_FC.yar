
rule Trojan_Win64_AbuseCommMain_FC{
	meta:
		description = "Trojan:Win64/AbuseCommMain.FC,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_00_0 = {74 00 6f 00 78 00 3a 00 31 00 34 00 36 00 30 00 37 00 44 00 39 00 44 00 37 00 38 00 43 00 44 00 44 00 32 00 43 00 45 00 37 00 31 00 38 00 42 00 36 00 43 00 37 00 46 00 34 00 43 00 34 00 30 00 38 00 37 00 41 00 36 00 46 00 38 00 45 00 45 00 33 00 37 00 45 00 33 00 37 00 45 00 41 00 39 00 33 00 38 00 33 00 30 00 42 00 36 00 44 00 30 00 32 00 41 00 41 00 30 00 44 00 44 00 42 00 38 00 38 00 32 00 36 00 36 00 } //1 tox:14607D9D78CDD2CE718B6C7F4C4087A6F8EE37E37EA93830B6D02AA0DDB88266
		$a_02_1 = {31 34 36 30 37 44 39 44 37 38 43 44 44 32 43 45 37 31 38 42 36 43 37 46 34 43 34 30 38 37 41 36 46 38 45 45 33 37 45 33 37 45 41 39 33 38 33 30 42 36 44 30 32 41 41 30 44 44 42 38 38 32 36 36 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4c 00 00 00 00 00 00 00 } //1
		$a_02_2 = {31 34 36 30 37 44 39 44 37 38 43 44 44 32 43 45 37 31 38 42 36 43 37 46 34 43 34 30 38 37 41 36 46 38 45 45 33 37 45 33 37 45 41 39 33 38 33 30 42 36 44 30 32 41 41 30 44 44 42 38 38 32 36 36 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 00 00 } //1
		$a_00_3 = {5c 74 6f 78 5c 31 34 36 30 37 44 39 44 37 38 43 44 44 32 43 45 37 31 38 42 36 43 37 46 34 43 34 30 38 37 41 36 46 38 45 45 33 37 45 33 37 45 41 39 33 38 33 30 42 36 44 30 32 41 41 30 44 44 42 38 38 32 36 36 2e 68 73 74 72 } //1 \tox\14607D9D78CDD2CE718B6C7F4C4087A6F8EE37E37EA93830B6D02AA0DDB88266.hstr
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_00_3  & 1)*1) >=1
 
}