
rule Trojan_Win64_AbuseCommBack_FF{
	meta:
		description = "Trojan:Win64/AbuseCommBack.FF,SIGNATURE_TYPE_PEHSTR,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {3c 00 70 00 3e 00 31 00 30 00 39 00 37 00 43 00 37 00 37 00 34 00 31 00 35 00 45 00 34 00 31 00 39 00 31 00 36 00 34 00 45 00 34 00 45 00 35 00 32 00 32 00 39 00 43 00 46 00 35 00 37 00 42 00 31 00 39 00 35 00 38 00 36 00 43 00 32 00 46 00 33 00 30 00 43 00 31 00 30 00 35 00 30 00 33 00 30 00 36 00 42 00 46 00 34 00 31 00 32 00 37 00 43 00 44 00 43 00 36 00 33 00 39 00 31 00 44 00 34 00 34 00 44 00 3c 00 2f 00 70 00 3e 00 } //1 <p>1097C77415E419164E4E5229CF57B19586C2F30C1050306BF4127CDC6391D44D</p>
		$a_01_1 = {31 30 39 37 43 37 37 34 31 35 45 34 31 39 31 36 34 45 34 45 35 32 32 39 43 46 35 37 42 31 39 35 38 36 43 32 46 33 30 43 31 30 35 30 33 30 36 42 46 34 31 32 37 43 44 43 36 33 39 31 44 34 34 44 00 00 00 00 00 00 00 00 } //1
		$a_01_2 = {74 61 62 6c 65 69 64 31 30 39 37 43 37 37 34 31 35 45 34 31 39 31 36 34 45 34 45 35 32 32 39 43 46 35 37 42 31 39 35 38 36 43 32 46 33 30 43 31 30 35 30 33 30 36 42 46 34 31 32 37 43 44 43 36 33 39 31 44 34 34 44 69 64 } //1 tableid1097C77415E419164E4E5229CF57B19586C2F30C1050306BF4127CDC6391D44Did
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}