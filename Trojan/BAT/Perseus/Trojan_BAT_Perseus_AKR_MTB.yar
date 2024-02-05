
rule Trojan_BAT_Perseus_AKR_MTB{
	meta:
		description = "Trojan:BAT/Perseus.AKR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0c 00 00 02 00 "
		
	strings :
		$a_80_0 = {43 43 38 30 43 34 41 31 31 34 34 43 31 37 45 32 36 42 34 38 43 46 35 32 31 31 34 35 39 46 35 34 45 33 38 46 41 43 38 41 35 30 43 42 39 45 41 45 44 45 30 36 37 46 38 33 36 32 32 32 43 32 44 39 } //CC80C4A1144C17E26B48CF5211459F54E38FAC8A50CB9EAEDE067F836222C2D9  02 00 
		$a_80_1 = {31 44 42 32 41 31 46 39 39 30 32 42 33 35 46 38 46 38 38 30 45 46 31 36 39 32 43 45 39 39 34 37 41 31 39 33 44 35 41 36 39 38 44 38 46 35 36 38 42 44 41 37 32 31 36 35 38 45 44 34 43 35 38 42 } //1DB2A1F9902B35F8F880EF1692CE9947A193D5A698D8F568BDA721658ED4C58B  01 00 
		$a_80_2 = {53 54 41 54 68 72 65 61 64 41 74 74 72 69 62 75 74 65 } //STAThreadAttribute  01 00 
		$a_80_3 = {43 6f 6d 70 69 6c 65 72 47 65 6e 65 72 61 74 65 64 41 74 74 72 69 62 75 74 65 } //CompilerGeneratedAttribute  01 00 
		$a_80_4 = {47 75 69 64 41 74 74 72 69 62 75 74 65 } //GuidAttribute  01 00 
		$a_80_5 = {47 65 6e 65 72 61 74 65 64 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //GeneratedCodeAttribute  01 00 
		$a_80_6 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //DebuggerNonUserCodeAttribute  01 00 
		$a_80_7 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //DebuggableAttribute  01 00 
		$a_80_8 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //DebuggerBrowsableAttribute  01 00 
		$a_80_9 = {45 64 69 74 6f 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //EditorBrowsableAttribute  01 00 
		$a_80_10 = {43 6f 6d 56 69 73 69 62 6c 65 41 74 74 72 69 62 75 74 65 } //ComVisibleAttribute  01 00 
		$a_80_11 = {41 73 73 65 6d 62 6c 79 54 69 74 6c 65 41 74 74 72 69 62 75 74 65 } //AssemblyTitleAttribute  00 00 
	condition:
		any of ($a_*)
 
}