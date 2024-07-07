
rule Backdoor_Linux_Gafgyt_AJ_xp{
	meta:
		description = "Backdoor:Linux/Gafgyt.AJ!xp,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2f 51 5a 75 51 5a 73 51 5a 72 51 5a 2f 51 5a 73 51 5a 62 51 5a 69 51 5a 6e 51 5a 2f 51 5a 64 51 5a 72 51 5a 6f 51 5a 70 51 5a 62 51 5a 65 51 5a 61 51 5a 72 } //1 /QZuQZsQZrQZ/QZsQZbQZiQZnQZ/QZdQZrQZoQZpQZbQZeQZaQZr
		$a_01_1 = {4b 51 5a 69 51 5a 6c 51 5a 6c 51 5a 69 51 5a 6e 51 5a 67 51 5a 20 51 5a 42 51 5a 6f 51 5a 74 51 5a 73 } //1 KQZiQZlQZlQZiQZnQZgQZ QZBQZoQZtQZs
		$a_01_2 = {42 51 5a 4f 51 5a 54 51 5a 4b 51 5a 49 51 5a 4c 51 5a 4c } //1 BQZOQZTQZKQZIQZLQZL
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}