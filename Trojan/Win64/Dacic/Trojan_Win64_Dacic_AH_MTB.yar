
rule Trojan_Win64_Dacic_AH_MTB{
	meta:
		description = "Trojan:Win64/Dacic.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 04 00 00 "
		
	strings :
		$a_01_0 = {65 78 65 63 28 63 6f 6d 70 69 6c 65 28 63 6f 64 65 2c 27 70 61 79 6c 6f 61 64 5f 6d 61 69 6e 2e 70 79 27 2c 27 65 78 65 63 27 29 2c 20 7b 27 5f 5f 6e 61 6d 65 5f 5f 27 3a 27 5f 5f 6d 61 69 6e 5f 5f 27 7d 29 } //10 exec(compile(code,'payload_main.py','exec'), {'__name__':'__main__'})
		$a_01_1 = {63 6f 64 65 20 3d 20 7a 69 70 66 69 6c 65 2e 5a 69 70 46 69 6c 65 28 74 29 2e 72 65 61 64 28 27 70 61 79 6c 6f 61 64 5f 6d 61 69 6e 2e 70 79 27 29 } //20 code = zipfile.ZipFile(t).read('payload_main.py')
		$a_01_2 = {69 66 20 27 70 61 79 6c 6f 61 64 5f 6d 61 69 6e 2e 70 79 27 20 69 6e 20 6e 61 6d 65 73 3a } //30 if 'payload_main.py' in names:
		$a_01_3 = {69 66 20 5f 69 73 5f 64 69 72 5f 6d 61 69 6e 28 74 29 3a 20 72 65 74 75 72 6e 20 5f 74 72 79 5f 66 69 6c 65 28 6f 73 2e 70 61 74 68 2e 6a 6f 69 6e 28 74 2c 27 70 61 79 6c 6f 61 64 5f 6d 61 69 6e 2e 70 79 27 29 29 } //40 if _is_dir_main(t): return _try_file(os.path.join(t,'payload_main.py'))
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*20+(#a_01_2  & 1)*30+(#a_01_3  & 1)*40) >=100
 
}