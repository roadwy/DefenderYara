
rule Trojan_BAT_Kryptik_ET_MTB{
	meta:
		description = "Trojan:BAT/Kryptik.ET!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1b 00 1b 00 13 00 00 0a 00 "
		
	strings :
		$a_03_0 = {11 05 11 0a 90 01 01 22 00 00 1b 11 0c 11 07 58 11 09 59 93 61 11 0b 90 01 01 22 00 00 1b 11 09 11 0c 58 1f 11 58 11 08 5d 93 61 d1 6f 90 02 04 26 90 00 } //01 00 
		$a_80_1 = {49 44 62 43 6f 6d 6d 61 6e 64 } //IDbCommand  01 00 
		$a_80_2 = {4f 6c 65 44 62 43 6f 6d 6d 61 6e 64 } //OleDbCommand  01 00 
		$a_80_3 = {57 65 62 52 65 73 70 6f 6e 73 65 } //WebResponse  01 00 
		$a_80_4 = {47 65 74 52 65 73 70 6f 6e 73 65 } //GetResponse  01 00 
		$a_80_5 = {47 65 74 4f 62 6a 65 63 74 56 61 6c 75 65 } //GetObjectValue  01 00 
		$a_80_6 = {47 65 74 52 65 73 6f 75 72 63 65 53 74 72 69 6e 67 } //GetResourceString  01 00 
		$a_80_7 = {43 6f 6d 70 61 72 65 53 74 72 69 6e 67 } //CompareString  01 00 
		$a_80_8 = {54 6f 53 74 72 69 6e 67 } //ToString  01 00 
		$a_80_9 = {4f 6c 65 44 62 43 6f 6e 6e 65 63 74 69 6f 6e } //OleDbConnection  01 00 
		$a_80_10 = {53 74 72 69 6e 67 42 75 69 6c 64 65 72 } //StringBuilder  01 00 
		$a_80_11 = {49 44 61 74 61 41 64 61 70 74 65 72 } //IDataAdapter  01 00 
		$a_80_12 = {49 44 62 44 61 74 61 41 64 61 70 74 65 72 } //IDbDataAdapter  01 00 
		$a_80_13 = {4f 6c 65 44 62 44 61 74 61 41 64 61 70 74 65 72 } //OleDbDataAdapter  01 00 
		$a_80_14 = {57 65 62 52 65 71 75 65 73 74 } //WebRequest  01 00 
		$a_80_15 = {43 6f 6e 74 61 69 6e 73 4b 65 79 } //ContainsKey  01 00 
		$a_80_16 = {73 65 74 5f 54 72 61 6e 73 70 61 72 65 6e 63 79 4b 65 79 } //set_TransparencyKey  01 00 
		$a_80_17 = {45 78 65 63 75 74 65 4e 6f 6e 51 75 65 72 79 } //ExecuteNonQuery  01 00 
		$a_80_18 = {53 79 73 74 65 6d 2e 53 65 63 75 72 69 74 79 } //System.Security  00 00 
	condition:
		any of ($a_*)
 
}