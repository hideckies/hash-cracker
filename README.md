# Hash Cracker

AI-powered Hash Identifier & Cracker online.   
Currently Hash Identifier is only available, Cracker is not yet. So I give some useful commands we can crack  right away.  
Hash Identifier uses Decision Forests model trained with [Yggdrasil](https://github.com/google/yggdrasil-decision-forests).

<br />

## All workflow automatically

Genrate DataSet, build the model, and start local web server.

```sh
./run.sh
```

### Generate Cracked Hashes

It generates hashes from rockyou.txt.  
To write the hashes to MongoDB, you need to your own credentials for MongoDB database.  
So copy the **.env_template** and rename it to **.env**, then set values.

```sh
./run_gen_cracked_hashes.sh
```

### Generate DataSet Only

```sh
./run_gen_dataset.sh
```

<br />

### Build a Model Only

```sh
./run_build_model.sh
```

<br />

### Start Local Web Server Only

```sh
./run_server.sh
```