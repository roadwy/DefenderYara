
rule Trojan_BAT_Zmutzy_NT_MTB{
	meta:
		description = "Trojan:BAT/Zmutzy.NT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {57 b7 a2 3f 09 0f 00 00 00 00 00 00 00 00 00 00 02 } //1
		$a_01_1 = {32 30 30 35 20 50 6f 6e 74 69 61 63 20 53 75 6e 66 69 72 65 } //1 2005 Pontiac Sunfire
		$a_01_2 = {61 52 33 6e 62 66 38 64 51 70 32 66 65 4c 6d 6b 33 31 2e 6c 53 66 67 41 70 61 74 6b 64 78 73 56 63 47 63 72 6b 74 6f 46 64 2e 72 65 73 6f 75 72 63 65 73 } //1 aR3nbf8dQp2feLmk31.lSfgApatkdxsVcGcrktoFd.resources
		$a_01_3 = {57 69 74 68 6f 6d 79 31 39 36 37 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 } //1 Withomy1967.Properties.R
		$a_01_4 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_5 = {52 69 6a 6e 64 61 65 6c 4d 61 6e 61 67 65 64 } //1 RijndaelManaged
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}